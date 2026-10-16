/* HBOM page (§4.4, round 71): two honest surfaces — the live-scan BOM
 * (empty until a scan runs) and the INDEPENDENT, unified estate HBOM:
 * one document over every persisted hardware asset, identity + evidence
 * references, content-addressed, pinnable, served verbatim with an
 * integrity self-check. The page must not invent estate rows, and an
 * empty estate must never render fabricated components. */
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { mockFetch, offlineFetch } from "../test/setup";
import Hbom from "./Hbom";

afterEach(() => {
  localStorage.clear();
  vi.restoreAllMocks();
});

const renderPage = () =>
  render(
    <MemoryRouter>
      <Hbom />
    </MemoryRouter>,
  );

const emptyLiveBom = {
  generated_at: null,
  cbom: { components: [], counts: {} },
  hbom: { components: [], counts: {} },
};

const estateDoc = {
  bomFormat: "Cryptoscan-HBOM",
  specVersion: "1.0",
  content_hash: "a".repeat(64),
  metadata: {
    generator: "cryptoscan-hbom-generator/1.0",
    environment: "default",
    as_of: "2026-10-16T09:00:00+00:00",
    component_count: 2,
    hsm_count: 1,
    tpm_count: 1,
    device_types: { hsm: 1, tpm: 1 },
    sources: ["live hardware inventory (hardware_assets)"],
    notes: ["No collector records hardware-to-system dependency edges yet."],
  },
  components: [
    {
      "bom-ref": "hw:hw-hsm-1", asset_id: "hw-hsm-1", name: "Utimaco CryptoServer",
      manufacturer: "Utimaco", model: "CryptoServer", device_type: "hsm",
      identity: { serial_reference: "SER-0001", hardware_revision: "C",
                  current_fingerprint: "f".repeat(64), previous_fingerprint: null },
      firmware: { details: { version: "4.21.2" }, last_checked: null },
      security_modules: { hsm: { fips_mode: true } },
      capabilities: null, crypto_capabilities: null,
      risk: { score: 40, level: "MEDIUM", last_change: null },
      evidence: { source: "live hardware inventory (hardware_assets)",
                  agent_id: "agent-dc-1", first_seen: null,
                  last_seen: "2026-10-16T09:00:00+00:00", last_verified: null,
                  last_crypto_check: null, evidence_ids: ["ev-h1", "ev-h2"] },
    },
    {
      "bom-ref": "hw:hw-tpm-1", asset_id: "hw-tpm-1", name: "Infineon SLB9665",
      manufacturer: "Infineon", model: "SLB9665", device_type: "tpm",
      identity: { serial_reference: null, hardware_revision: null,
                  current_fingerprint: "b".repeat(64), previous_fingerprint: null },
      firmware: { details: null, last_checked: null },
      security_modules: { tpm: { spec: "2.0" } },
      capabilities: null, crypto_capabilities: null,
      risk: { score: 10, level: "LOW", last_change: null },
      evidence: { source: "live hardware inventory (hardware_assets)",
                  agent_id: "agent-branch-7", first_seen: null,
                  last_seen: "2026-10-15T09:00:00+00:00", last_verified: null,
                  last_crypto_check: null, evidence_ids: ["ev-t1"] },
    },
  ],
  hsm_fleet: { count: 1, asset_ids: ["hw-hsm-1"] },
  tpm_fleet: { count: 1, asset_ids: ["hw-tpm-1"] },
  dependencies: [],
};

const snapshotRow = {
  snapshot_id: "snap-hbom-1", environment: "default", content_hash: "a".repeat(64),
  component_count: 2, generator: "api", created_by: "auditor",
  snapshotted_at: "2026-10-16T10:00:00+00:00", as_of: "2026-10-16T09:00:00+00:00",
  verify_path: "/api/v1/hbom/snapshots/snap-hbom-1",
};

describe("HBOM page", () => {
  it("renders the estate document with identity, evidence and its content hash", async () => {
    mockFetch({
      "/api/v1/live-scan/bom": emptyLiveBom,
      "/api/v1/hbom": estateDoc,
      "/api/v1/hbom/snapshots": { snapshots: [snapshotRow], count: 1, note: "Each snapshot is a pinned rendering." },
    });
    renderPage();

    await waitFor(() => expect(screen.getByText("Unified estate HBOM")).toBeTruthy());
    // per-asset identity rows — never invented
    expect(await screen.findByText("hw-hsm-1")).toBeTruthy();
    expect(screen.getByText("Utimaco CryptoServer")).toBeTruthy();
    expect(screen.getByText("hw-tpm-1")).toBeTruthy();
    // the content address is shown (truncated)
    expect(screen.getByText(/SHA-256 a{16}…/)).toBeTruthy();
    // evidence references per component
    expect(screen.getByText("agent-dc-1")).toBeTruthy();
    expect(screen.getByText("2 refs")).toBeTruthy();
    // fleet aggregates
    expect(screen.getByText(/HSM 1/)).toBeTruthy();
    // the live-scan panel stays honest about being empty
    expect(screen.getByText(/No HBOM yet/i)).toBeTruthy();
  });

  it("renders an honest empty estate — no fabricated components", async () => {
    const empty = {
      ...estateDoc,
      content_hash: "0".repeat(64),
      components: [],
      hsm_fleet: { count: 0, asset_ids: [] },
      tpm_fleet: { count: 0, asset_ids: [] },
      metadata: { ...estateDoc.metadata, component_count: 0, hsm_count: 0, tpm_count: 0,
                  device_types: {}, as_of: null },
    };
    mockFetch({
      "/api/v1/live-scan/bom": emptyLiveBom,
      "/api/v1/hbom": empty,
      "/api/v1/hbom/snapshots": { snapshots: [], count: 0, note: "" },
    });
    renderPage();

    await waitFor(() => expect(screen.getByText(/No hardware assets are persisted/i)).toBeTruthy());
    expect(
      screen.getByText((_, el) => el?.textContent === "0 ESTATE COMPONENTS"),
    ).toBeTruthy();
    expect(screen.getByText(/No estate snapshots pinned yet/i)).toBeTruthy();
    expect(screen.queryByText("hw-hsm-1")).toBeNull();
  });

  it("pins the estate document and verifies the pinned snapshot verbatim", async () => {
    const fetchMock = mockFetch({
      "/api/v1/live-scan/bom": emptyLiveBom,
      "/api/v1/hbom": estateDoc,
      "/api/v1/hbom/snapshot": () => ({ ...snapshotRow, created: true, note: "Estate HBOM pinned." }),
      "/api/v1/hbom/snapshots": () =>
        ({ snapshots: [snapshotRow], count: 1, note: "Each snapshot is a pinned rendering." }),
      "/api/v1/hbom/snapshots/snap-hbom-1": {
        ...snapshotRow, integrity: "OK",
        integrity_note: "SHA-256 over the stored payload matches the pinned content hash.",
        payload: estateDoc,
      },
    });
    renderPage();

    await waitFor(() => expect(screen.getByText("Unified estate HBOM")).toBeTruthy());

    // pin the current estate document
    fireEvent.click(await screen.findByText("Pin current estate HBOM"));
    await waitFor(() => expect(screen.getByText(/Estate HBOM pinned/i)).toBeTruthy());
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/hbom/snapshot", expect.objectContaining({ method: "POST" }));

    // verify & view serves the stored document verbatim with its verdict
    fireEvent.click(await screen.findByText("Verify & View"));
    expect(await screen.findByText("VERBATIM DOCUMENT")).toBeTruthy();
    expect(screen.getByText("OK")).toBeTruthy();
    expect(screen.getByText(/matches the pinned content hash/i)).toBeTruthy();
    expect(screen.getByText(/3 references total/i)).toBeTruthy();
    // the stored payload itself is rendered
    expect(screen.getByText(/"bomFormat"/)).toBeTruthy();
  });

  it("shows the MISMATCH verdict when a pinned payload was mutated", async () => {
    mockFetch({
      "/api/v1/live-scan/bom": emptyLiveBom,
      "/api/v1/hbom": estateDoc,
      "/api/v1/hbom/snapshots": { snapshots: [snapshotRow], count: 1, note: "" },
      "/api/v1/hbom/snapshots/snap-hbom-1": {
        ...snapshotRow, integrity: "MISMATCH",
        integrity_note: "Stored payload does NOT match its pinned content hash — the document was mutated after pinning. Do not trust it.",
        payload: estateDoc,
      },
    });
    renderPage();

    fireEvent.click(await screen.findByText("Verify & View"));
    expect(await screen.findByText("MISMATCH")).toBeTruthy();
    expect(screen.getByText(/Do not trust it/i)).toBeTruthy();
  });

  it("stays honest when the backend is unreachable", async () => {
    offlineFetch();
    renderPage();

    await waitFor(() => expect(screen.getByText(/Estate document unavailable/i)).toBeTruthy());
    expect(screen.getByText(/Snapshot list unavailable/i)).toBeTruthy();
    expect(screen.queryByText("hw-hsm-1")).toBeNull();
  });
});
