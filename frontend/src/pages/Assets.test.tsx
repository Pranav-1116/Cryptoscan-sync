import { describe, expect, it } from "vitest";
import { act, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { renderWithProviders } from "../test/render";
import { mockFetch } from "../test/setup";
import { setActiveTenantId, setToken } from "../lib/api";
import Assets from "./Assets";

const listPath = "/api/v1/assets";

function statusResponse(status: number) {
  return new Response(JSON.stringify({ detail: "restricted" }), { status });
}

describe("asset inventory from the live API", () => {
  it("renders sparse rows without inventing identity, crypto, ownership, dates, evidence, or verdicts", async () => {
    mockFetch({
      [listPath]: { assets: [{ id: "asset-sparse" }], total_count: 1, page: 1, page_size: 100 },
      "/api/v1/assets/asset-sparse": { id: "asset-sparse", evidence_ids: [] },
    });
    renderWithProviders(<Assets />);
    await screen.findByText("Not observed; integrity not verified");
    // The overview never upgrades absent facts to a reassuring result.
    expect(screen.getByRole("heading", { name: "asset-sparse" })).toBeInTheDocument();
    expect(screen.getByText("Key size not observed", { exact: false })).toBeInTheDocument();
    expect(screen.getByText("Not assessed by this endpoint")).toBeInTheDocument();
    expect(screen.queryByText(/RSA|2048|TLS 1\.3|Production Cluster|Security Operations|OBS-|Integrity Verified|No drift/)).toBeNull();
    expect(screen.queryByRole("link", { name: /Evidence/i })).toBeNull();
    fireEvent.click(screen.getByRole("tab", { name: "Evidence" }));
    expect(await screen.findByText("No evidence IDs are associated with this asset in the detail response. Integrity not verified.")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: "Facts" }));
    expect(screen.getByText(/The fact join needs this asset's algorithm and source path/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: "Dependencies" }));
    expect(await screen.findByText(/not linked to any system/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: "Policy" }));
    expect(screen.getByText("No policy verdict is provided by this asset endpoint.")).toBeInTheDocument();
  });

  it("renders only returned columns and detail evidence IDs; preserves search, selection, and tenant authentication", async () => {
    setToken("test-token");
    localStorage.setItem("cryptoscan_tenant", "test-tenant");
    const first = {
      id: "asset-1", algorithm: "ECDSA", key_size: 256, file_path: "src/certs/client.pem",
      owner: "Platform Team", lifecycle_state: "DISCOVERED", created_at: "2025-01-02T03:00:00Z",
      updated_at: "2025-01-03T03:00:00Z",
      extra: { first_seen_at: "2025-01-01T01:00:00Z", last_seen_at: "2025-01-03T01:00:00Z", protocol: "TLS 1.2" },
    };
    const second = { id: "asset-2", algorithm: "AES", file_path: "src/crypto/encrypt.ts" };
    const fetchSpy = mockFetch({
      [listPath]: { assets: [first, second], total_count: 2, page: 1, page_size: 100 },
      "/api/v1/assets/asset-1": { ...first, evidence_ids: ["ev-1", "ev-2"] },
      "/api/v1/assets/asset-2": { ...second, evidence_ids: [] },
    });
    renderWithProviders(<Assets />);
    await screen.findByRole("heading", { name: "ECDSA" });
    await waitFor(() => expect(screen.getByText("2 linked ID(s); integrity not verified")).toBeInTheDocument());
    expect(screen.getByText("ECDSA · 256 bits")).toBeInTheDocument();
    expect(screen.getByText("TLS 1.2")).toBeInTheDocument();
    expect(screen.getByText("2025-01-02T03:00:00Z / 2025-01-03T03:00:00Z")).toBeInTheDocument();
    expect(screen.getByText("2025-01-01T01:00:00Z / 2025-01-03T01:00:00Z")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: "Evidence" }));
    expect(screen.getByText("ev-1")).toBeInTheDocument();
    expect(screen.getByText("ev-2")).toBeInTheDocument();
    expect(screen.queryByText(/Integrity Verified|HMAC-SHA256|WORM audit pack/)).toBeNull();
    expect(screen.queryByRole("link", { name: /Evidence/i })).toBeNull();
    const calls = fetchSpy.mock.calls.filter(([path]) => String(path).startsWith("/api/v1/assets"));
    expect(calls).toHaveLength(2);
    for (const [, init] of calls) {
      expect(init?.headers).toMatchObject({ Authorization: "Bearer test-token", "X-Tenant-ID": "test-tenant" });
      expect(init?.credentials).toBe("include");
    }
    fireEvent.change(screen.getByRole("searchbox", { name: "Search assets" }), { target: { value: "encrypt.ts" } });
    const assetButton = screen.getByRole("button", { name: /AES/ });
    expect(assetButton).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /ECDSA/ })).toBeNull();
    fireEvent.click(assetButton);
    await screen.findByRole("heading", { name: "AES" });
    await waitFor(() => expect(fetchSpy.mock.calls.some(([path]) => String(path) === "/api/v1/assets/asset-2")).toBe(true));
    expect(within(screen.getByRole("button", { name: /AES/ })).getByText("Owner unknown")).toBeInTheDocument();
  });

  it("loads beyond 100 without duplicate IDs and reports the server total", async () => {
    const firstPage = Array.from({ length: 100 }, (_, i) => ({ id: `asset-${i + 1}`, algorithm: `ALG-${i + 1}` }));
    const fetchSpy = mockFetch({
      [listPath]: (url: string) => url.includes("page=2")
        ? { assets: [firstPage[99], { id: "asset-101", algorithm: "ALG-101" }], total_count: 101, page: 2, page_size: 100 }
        : { assets: firstPage, total_count: 101, page: 1, page_size: 100 },
      "/api/v1/assets/*": (url: string) => ({ id: url.split("/").pop(), evidence_ids: [] }),
    });
    renderWithProviders(<Assets />);
    expect(await screen.findByText("Loaded 100 of 101 assets")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Load more assets" }));
    expect(await screen.findByText("Loaded 101 of 101 assets")).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: /ALG-100/ })).toHaveLength(1);
    expect(screen.queryByRole("button", { name: "Load more assets" })).toBeNull();
    fireEvent.change(screen.getByRole("searchbox", { name: "Search assets" }), { target: { value: "ALG-101" } });
    fireEvent.click(screen.getByRole("button", { name: /ALG-101/ }));
    await screen.findByRole("heading", { name: "ALG-101" });
    expect(fetchSpy.mock.calls.filter(([path]) => String(path) === "/api/v1/assets?page=2&page_size=100")).toHaveLength(1);
  });

  it("keeps loaded assets and exposes later-page failure with retry", async () => {
    let attempts = 0;
    const firstPage = Array.from({ length: 100 }, (_, i) => ({ id: `asset-${i}`, algorithm: `ALG-${i}` }));
    mockFetch({
      [listPath]: (url: string) => {
        if (url.includes("page=2")) return ++attempts === 1 ? statusResponse(503) : { assets: [{ id: "asset-100", algorithm: "ALG-100" }], total_count: 101 };
        return { assets: firstPage, total_count: 101 };
      },
      "/api/v1/assets/*": (url: string) => ({ id: url.split("/").pop(), evidence_ids: [] }),
    });
    renderWithProviders(<Assets />);
    await screen.findByText("Loaded 100 of 101 assets");
    fireEvent.click(screen.getByRole("button", { name: "Load more assets" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("page 2 of assets (HTTP 503)");
    expect(screen.getByText("Loaded 100 of 101 assets")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Load more assets" }));
    expect(await screen.findByText("Loaded 101 of 101 assets")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("clears old tenant assets and ignores late detail responses on a same-tab switch", async () => {
    localStorage.setItem("cryptoscan_tenant", "tenant-a");
    let resolveOld!: (value: unknown) => void;
    const oldDetail = new Promise<unknown>((resolve) => { resolveOld = resolve; });
    mockFetch({
      [listPath]: (_url: string, init?: RequestInit) => (init?.headers as Record<string, string>)?.["X-Tenant-ID"] === "tenant-a"
        ? { assets: [{ id: "a", algorithm: "Tenant A cipher" }], total_count: 1 }
        : { assets: [{ id: "b", algorithm: "Tenant B cipher" }], total_count: 1 },
      "/api/v1/assets/a": () => oldDetail,
      "/api/v1/assets/b": { id: "b", algorithm: "Tenant B cipher", evidence_ids: ["b-evidence"] },
    });
    renderWithProviders(<Assets />);
    await screen.findByRole("heading", { name: "Tenant A cipher" });
    await waitFor(() => expect(screen.getByText("Loading evidence IDs...")).toBeInTheDocument());
    act(() => setActiveTenantId("tenant-b"));
    expect(screen.queryByRole("heading", { name: "Tenant A cipher" })).toBeNull();
    await screen.findByRole("heading", { name: "Tenant B cipher" });
    await screen.findByText("1 linked ID(s); integrity not verified");
    await act(async () => { resolveOld({ id: "a", evidence_ids: ["a-evidence"] }); });
    expect(screen.queryByText(/Tenant A cipher|a-evidence/)).toBeNull();
  });

  it("ignores a late inventory response from the previous tenant", async () => {
    localStorage.setItem("cryptoscan_tenant", "tenant-a");
    let resolveOld!: (value: unknown) => void;
    const oldList = new Promise<unknown>((resolve) => { resolveOld = resolve; });
    const fetchSpy = mockFetch({
      [listPath]: (_url: string, init?: RequestInit) => (init?.headers as Record<string, string>)?.["X-Tenant-ID"] === "tenant-a"
        ? oldList
        : { assets: [{ id: "b", algorithm: "Tenant B cipher" }], total_count: 1 },
      "/api/v1/assets/b": { id: "b", algorithm: "Tenant B cipher", evidence_ids: [] },
    });
    renderWithProviders(<Assets />);
    await waitFor(() => expect(fetchSpy.mock.calls.some(([url]) => String(url).includes("page=1"))).toBe(true));
    act(() => setActiveTenantId("tenant-b"));
    await screen.findByRole("heading", { name: "Tenant B cipher" });
    await act(async () => { resolveOld({ assets: [{ id: "a", algorithm: "Tenant A cipher" }], total_count: 1 }); });
    expect(screen.queryByText("Tenant A cipher")).toBeNull();
    expect(screen.getByText("Loaded 1 of 1 assets")).toBeInTheDocument();
  });

  it("clears visible assets when authentication changes and the new request is denied", async () => {
    setToken("test-token");
    mockFetch({
      [listPath]: (_url: string, init?: RequestInit) => (init?.headers as Record<string, string>)?.Authorization
        ? { assets: [{ id: "a", algorithm: "Authenticated asset" }], total_count: 1 }
        : statusResponse(401),
      "/api/v1/assets/a": { id: "a", evidence_ids: [] },
    });
    renderWithProviders(<Assets />);
    await screen.findByRole("heading", { name: "Authenticated asset" });
    act(() => setToken(null));
    expect(screen.queryByRole("heading", { name: "Authenticated asset" })).toBeNull();
    expect(await screen.findByRole("alert")).toHaveTextContent("Authentication required");
  });

  it.each([401, 403])("distinguishes HTTP %i from a verified empty inventory", async (status) => {
    mockFetch({ [listPath]: statusResponse(status) });
    renderWithProviders(<Assets />);
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(status === 401 ? "Authentication required" : "Access denied");
    expect(screen.queryByText("No cryptographic assets discovered yet")).toBeNull();
  });

  it("distinguishes offline service from an empty inventory", async () => {
    renderWithProviders(<Assets />);
    expect(await screen.findByRole("alert")).toHaveTextContent("offline or unreachable");
    expect(screen.queryByText("No cryptographic assets discovered yet")).toBeNull();
  });

  it("rejects rows without real IDs rather than fabricating asset identifiers", async () => {
    mockFetch({ [listPath]: { assets: [{ algorithm: "RSA" }], total_count: 1 } });
    renderWithProviders(<Assets />);
    expect(await screen.findByRole("alert")).toHaveTextContent("records without valid IDs");
    expect(screen.queryByText(/AST-1000|No cryptographic assets discovered yet/)).toBeNull();
  });

  it("shows a genuine empty inventory only when the API returns an empty list", async () => {
    mockFetch({ [listPath]: { assets: [], total_count: 0, page: 1, page_size: 100 } });
    renderWithProviders(<Assets />);
    expect(await screen.findByText("No cryptographic assets discovered yet")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it.each([403, "offline"])("does not treat %s asset detail as absent or verified evidence", async (outcome) => {
    mockFetch({
      [listPath]: { assets: [{ id: "asset-1", algorithm: "AES" }], total_count: 1 },
      "/api/v1/assets/asset-1": outcome === 403 ? statusResponse(403) : () => { throw new TypeError("Failed to fetch"); },
    });
    renderWithProviders(<Assets />);
    await screen.findByRole("heading", { name: "AES" });
    fireEvent.click(screen.getByRole("tab", { name: "Evidence" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(outcome === 403 ? "Access denied to asset details and evidence" : "Asset details and evidence are offline or unreachable");
    expect(screen.queryByText(/No evidence IDs are associated/)).toBeNull();
  });
});

/* §5/§4.2 (round 62): the asset detail shows the IDENTITY SPINE — the
 * canonical key that joins this asset to its evidence, fact and BOM
 * component rows. Absent stays absent; nothing is invented. */
describe("asset identity spine in the detail view", () => {
  it("shows the canonical asset_key when the API returns one", async () => {
    mockFetch({
      [listPath]: { assets: [
        { id: "asset-1", algorithm: "RSA-2048", asset_key: "fact:v1:9f86d0", file_path: "src/Keys.java" },
      ], total_count: 1, page: 1, page_size: 100 },
      "/api/v1/assets/asset-1": { id: "asset-1", algorithm: "RSA-2048", asset_key: "fact:v1:9f86d0", file_path: "src/Keys.java", evidence_ids: ["ev-1"] },
    });
    renderWithProviders(<Assets />);
    await screen.findByRole("heading", { name: "RSA-2048" });
    expect(screen.getByText("fact:v1:9f86d0")).toBeInTheDocument();
    expect(screen.getByText(/joins this asset to its evidence, fact and BOM component rows/)).toBeInTheDocument();
  });

  it("says Not observed when no spine key exists — never invents identity", async () => {
    mockFetch({
      [listPath]: { assets: [
        { id: "asset-old", algorithm: "DES", file_path: "old/X.java" },
      ], total_count: 1, page: 1, page_size: 100 },
      "/api/v1/assets/asset-old": { id: "asset-old", algorithm: "DES", file_path: "old/X.java", evidence_ids: [] },
    });
    renderWithProviders(<Assets />);
    await screen.findByRole("heading", { name: "DES" });
    const rows = screen.getAllByText("Not observed");
    expect(rows.length).toBeGreaterThanOrEqual(1); // the spine row says so honestly
  });
});

describe("asset detail → fact and graph cross-links (round 64)", () => {
  const spine = "fact:v1:9a8b7c";
  const aesAsset = {
    id: "asset-aes", algorithm: "AES-256", purpose: "ENCRYPTION", mode: "GCM",
    key_size: 256, file_path: "src/pay/Cipher.java", asset_key: spine,
    owner: "Payments", lifecycle_state: "ACTIVE",
  };
  const factRow = {
    asset_key: spine,
    fact: { algorithm: "AES-256", purpose: "ENCRYPTION", file_path: "src/pay/Cipher.java", key_size: 256, mode: "GCM" },
    observation_count: 3, first_seen: "2026-09-01T00:00:00Z", last_seen: "2026-10-05T00:00:00Z",
    scanners: ["ast-scanner", "regex-scanner"], confidences: ["HIGH"],
    hardcoded_key_observations: 0,
    evidence_ids: ["ev-1", "ev-2", "ev-3"], evidence_count: 3, evidence_truncated: false,
    fresh: true,
  };

  it("joins the asset to its fact row on the identity spine", async () => {
    mockFetch({
      [listPath]: { assets: [aesAsset], total_count: 1, page: 1, page_size: 100 },
      "/api/v1/assets/asset-aes": { ...aesAsset, evidence_ids: ["ev-1"] },
      "/api/v1/facts/store": { model: "fact-store/read-v1", freshness: "current", facts: [factRow], facts_returned: 1, facts_matching: 1 },
    });
    renderWithProviders(<Assets />);
    await screen.findByRole("heading", { name: "AES-256" });
    fireEvent.click(screen.getByRole("tab", { name: "Facts" }));
    expect(await screen.findByText(/the same canonical spine key on the asset row and the fact row/)).toBeInTheDocument();
    expect(screen.getByText(spine)).toBeInTheDocument();
    expect(screen.getByText(/Observed 3 time\(s\)/)).toBeInTheDocument();
    expect(screen.getByText(/Evidence behind this fact: 3 row\(s\)/)).toBeInTheDocument();
    expect(screen.getByText(/integrity not verified here/)).toBeInTheDocument();
    expect(screen.getByText(/current \(the rebuild covers/)).toBeInTheDocument();
  });

  it("says honestly when no fact row matches the identity — no fabricated fact", async () => {
    const stranger = { ...factRow, asset_key: "fact:v1:other", fact: { ...factRow.fact, key_size: 128 } };
    mockFetch({
      [listPath]: { assets: [aesAsset], total_count: 1, page: 1, page_size: 100 },
      "/api/v1/assets/asset-aes": { ...aesAsset, evidence_ids: [] },
      "/api/v1/facts/store": { model: "fact-store/read-v1", facts: [stranger], facts_returned: 1, facts_matching: 1 },
    });
    renderWithProviders(<Assets />);
    await screen.findByRole("heading", { name: "AES-256" });
    fireEvent.click(screen.getByRole("tab", { name: "Facts" }));
    expect(await screen.findByText(/No fact row in the store matches this asset's identity/)).toBeInTheDocument();
    expect(screen.getByText(/\(1 candidate row/)).toBeInTheDocument();
  });

  it("walks the real blast radius from the asset and deep-links into the graph view", async () => {
    mockFetch({
      [listPath]: { assets: [aesAsset], total_count: 1, page: 1, page_size: 100 },
      "/api/v1/assets/asset-aes": { ...aesAsset, evidence_ids: ["ev-1"] },
      "/api/v1/graph/blast-radius": {
        start: "asset-aes", start_kind: "asset", owning_systems: ["sys-payments"],
        systems: [{ id: "sys-batch", name: "Batch Settlement", hops: 2 }],
        hops: 5, nodes_visited: 2, backend: "memory",
      },
    });
    renderWithProviders(<Assets />);
    await screen.findByRole("heading", { name: "AES-256" });
    fireEvent.click(screen.getByRole("tab", { name: "Dependencies" }));
    expect(await screen.findByText(/Owning system\(s\): sys-payments/)).toBeInTheDocument();
    expect(screen.getByText(/Batch Settlement/)).toBeInTheDocument();
    expect(screen.getByText(/· 2 hops/)).toBeInTheDocument();
    expect(screen.getByText(/declared or adopted relationships, not observed traffic/)).toBeInTheDocument();
    const link = screen.getByRole("link", { name: "Open in Dependency Graph" });
    expect(link).toHaveAttribute("href", "/dependency-graph?asset=asset-aes");
  });
  it("shows the remediation tasks that reference this asset's evidence (round 75)", async () => {
    mockFetch({
      [listPath]: { assets: [aesAsset], total_count: 1, page: 1, page_size: 100 },
      "/api/v1/assets/asset-aes": { ...aesAsset, evidence_ids: ["ev-1"] },
      "/api/v1/remediation/tasks": {
        tasks: [{
          id: "task-75", evidence_id: "ev-1", scan_id: "scan-77", rule_id: "P019",
          category: "weak_cipher", priority: "P0", replace_with: "AES-256-GCM",
          original_finding: {}, target_location: "repo", status: "VERIFIED",
          owner: "crypto-team", notes: null, created_by: "analyst", source: "manual",
        }],
        total: 1, page: 1, page_size: 20,
      },
    });
    renderWithProviders(<Assets />);
    await screen.findByRole("heading", { name: "AES-256" });
    fireEvent.click(screen.getByRole("tab", { name: "Remediation" }));
    // the task renders with its rule, evidence binding, owner and status
    expect(await screen.findByText(/P019/)).toBeInTheDocument();
    expect(screen.getByText(/evidence ev-1/)).toBeInTheDocument();
    expect(screen.getByText(/crypto-team/)).toBeInTheDocument();
    expect(screen.getByText("VERIFIED")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Open task lifecycle view" })).toHaveAttribute("href", "/remediation");
  });

  it("states honestly when no remediation task references the asset's evidence", async () => {
    mockFetch({
      [listPath]: { assets: [aesAsset], total_count: 1, page: 1, page_size: 100 },
      "/api/v1/assets/asset-aes": { ...aesAsset, evidence_ids: ["ev-1"] },
      "/api/v1/remediation/tasks": { tasks: [], total: 0, page: 1, page_size: 20 },
    });
    renderWithProviders(<Assets />);
    await screen.findByRole("heading", { name: "AES-256" });
    fireEvent.click(screen.getByRole("tab", { name: "Remediation" }));
    expect(await screen.findByText(/No remediation tasks reference this asset's evidence/)).toBeInTheDocument();
    expect(screen.getByText(/not invented here/)).toBeInTheDocument();
  });
});

describe("asset inventory — evidence classification (gap analysis §A)", () => {
  it("every record shows its evidence classification from the API", async () => {
    mockFetch({
      [listPath]: {
        assets: [
          {
            id: "asset-classified",
            evidence_classification: {
              strongest_level: "RUNTIME_OBSERVED",
              note: "collector source 'runtime process probe' observed a running system",
            },
          },
          { id: "asset-silent" },
        ],
        total_count: 2, page: 1, page_size: 100,
      },
      "/api/v1/assets/asset-classified": {
        id: "asset-classified",
        evidence_ids: ["ev-1"],
        evidence_classification: {
          strongest_level: "RUNTIME_OBSERVED",
          note: "collector source 'runtime process probe' observed a running system",
        },
      },
      "/api/v1/assets/asset-silent": { id: "asset-silent", evidence_ids: [] },
    });
    renderWithProviders(<Assets />);
    await screen.findByRole("heading", { name: "asset-classified" });
    expect(screen.getByText("Evidence: RUNTIME_OBSERVED")).toBeInTheDocument();
    // a record whose evidence level is not recorded shows UNCLASSIFIED —
    // unknown, never promoted by assumption
    expect(screen.getByText("Evidence: UNCLASSIFIED")).toBeInTheDocument();
  });

  it("the detail panel names the level and the rule behind it", async () => {
    mockFetch({
      [listPath]: {
        assets: [{
          id: "asset-classified",
          evidence_classification: {
            strongest_level: "STATIC_REFERENCE",
            note: "named in source at a line: referenced, not run",
          },
        }],
        total_count: 1, page: 1, page_size: 100,
      },
      "/api/v1/assets/asset-classified": {
        id: "asset-classified",
        evidence_ids: ["ev-1"],
        evidence_classification: {
          strongest_level: "STATIC_REFERENCE",
          note: "named in source at a line: referenced, not run",
        },
      },
    });
    renderWithProviders(<Assets />);
    await screen.findByRole("heading", { name: "asset-classified" });
    expect(screen.getByTestId("evidence-classification")).toHaveTextContent("STATIC_REFERENCE");
    expect(screen.getByText(/referenced, not run/)).toBeInTheDocument();
  });
});
