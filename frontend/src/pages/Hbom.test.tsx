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
const olderSnapshotRow = {
  ...snapshotRow,
  snapshot_id: "snap-hbom-0", content_hash: "0".repeat(64),
  component_count: 2, snapshotted_at: "2026-10-15T10:00:00+00:00",
  as_of: "2026-10-15T09:00:00+00:00",
  verify_path: "/api/v1/hbom/snapshots/snap-hbom-0",
};

describe("HBOM page", () => {
  it("renders the estate document with identity, evidence and its content hash", async () => {
    mockFetch({
      "/api/v1/live-scan/bom": emptyLiveBom,
      "/api/v1/hbom": estateDoc,
      "/api/v1/hbom/snapshots": { snapshots: [snapshotRow], count: 1, note: "Each snapshot is a pinned rendering." },
    });
    renderPage();

    await waitFor(() => expect(screen.getByText("Unified Estate HBOM")).toBeTruthy());
    // per-asset identity rows — never invented
    expect(await screen.findByText("hw-hsm-1")).toBeTruthy();
    expect(screen.getByText("Utimaco CryptoServer")).toBeTruthy();
    expect(screen.getByText("hw-tpm-1")).toBeTruthy();
    // the content address is shown (truncated)
    expect(screen.getByText(/SHA-256 a{12}…/)).toBeTruthy();
    // evidence references per component
    expect(screen.getByText("agent-dc-1")).toBeTruthy();
    expect(screen.getByText("2 refs")).toBeTruthy();
    // fleet aggregates
    expect(screen.getAllByText(/HSM 1/).length).toBeGreaterThan(0);
    // the live-scan panel stays honest about being empty
    expect(screen.getByText(/No HBOM yet/i)).toBeTruthy();
  });

  it("marks a device that came from a stored estate observation, not from an agent", async () => {
    const observationSource = "estate observation (HARDWARE/HSM assets)";
    const mixed = {
      ...estateDoc,
      metadata: {
        ...estateDoc.metadata,
        component_count: 3,
        hsm_count: 2,
        sources: ["live hardware inventory (hardware_assets)", observationSource],
        notes: [
          "No collector records hardware-to-system dependency edges yet.",
          "1 device(s) come from the stored estate observation, not from the live agent; each carries the observation's evidence ids and is declared, not fingerprinted.",
        ],
      },
      components: [
        ...estateDoc.components,
        {
          "bom-ref": "hw:hardware:abc123", asset_id: "hardware:abc123", name: "SYNTHETIC-Vendor-000 LAB-0",
          manufacturer: "SYNTHETIC-Vendor-000", model: "LAB-0", device_type: "payment-hsm",
          identity: { serial_reference: null, hardware_revision: null,
                      current_fingerprint: null, previous_fingerprint: null },
          firmware: { details: "1.0-SYNTHETIC", last_checked: null },
          security_modules: { hsm: { declared_only: true } },
          capabilities: null, crypto_capabilities: ["AES-256"],
          risk: { score: null, level: null, last_change: null },
          evidence: { source: observationSource, agent_id: null, first_seen: null,
                      last_seen: null, last_verified: null, last_crypto_check: null,
                      evidence_ids: ["ev-o1", "ev-o2", "ev-o3"] },
        },
      ],
    };
    mockFetch({
      "/api/v1/live-scan/bom": emptyLiveBom,
      "/api/v1/hbom": mixed,
      "/api/v1/hbom/snapshots": { snapshots: [], count: 0, note: "" },
    });
    renderPage();

    await waitFor(() => expect(screen.getByText("Unified Estate HBOM")).toBeTruthy());
    // the imported row says so, in the row and in the document's notes
    expect(await screen.findByText("imported")).toBeTruthy();
    expect(screen.getByText("no agent (imported)")).toBeTruthy();
    expect(screen.getByText(/declared, not fingerprinted/)).toBeTruthy();
    // and the agent-fingerprinted row is left alone: exactly one imported badge
    expect(screen.getAllByText("imported")).toHaveLength(1);
    expect(screen.getByText("agent-dc-1")).toBeTruthy();
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

    await waitFor(() => expect(screen.getByText(/No hardware assets persisted for this environment/i)).toBeTruthy());
    expect(screen.getByText("0 ESTATE")).toBeTruthy();
    expect(screen.getByText(/No snapshots pinned yet/i)).toBeTruthy();
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

    await waitFor(() => expect(screen.getByText("Unified Estate HBOM")).toBeTruthy());

    // pin the current estate document
    fireEvent.click(await screen.findByText("Pin current →"));
    await waitFor(() => expect(screen.getByText(/Estate HBOM pinned/i)).toBeTruthy());
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/hbom/snapshot", expect.objectContaining({ method: "POST" }));

    // verify & view serves the stored document verbatim with its verdict
    fireEvent.click(await screen.findByText("Verify & View"));
    expect(await screen.findByText("VERBATIM DOCUMENT")).toBeTruthy();
    expect(screen.getByText("OK")).toBeTruthy();
    expect(screen.getByText(/matches the pinned content hash/i)).toBeTruthy();
    expect(screen.getByText("EVIDENCE REFS").parentElement).toHaveTextContent("3");
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

  it("compares two pins — devices added/removed and field drift on survivors", async () => {
    const fetchMock = mockFetch({
      "/api/v1/live-scan/bom": emptyLiveBom,
      "/api/v1/hbom": estateDoc,
      "/api/v1/hbom/snapshots": { snapshots: [snapshotRow, olderSnapshotRow], count: 2, note: "" },
      "/api/v1/hbom/snapshots/snap-hbom-1/diff": (url: string) => {
        // route key has the query stripped by the harness; both keying
        // modes answer from the same pinned pair
        if (url.includes("key_by=bom_ref")) {
          return {
            target: snapshotRow, baseline: olderSnapshotRow, note: "",
            diff: {
              key_by: "bom_ref", identical: false, excluded_paths: [],
              components: {
                key_by: "bom_ref",
                added: [{ key: "hw:hw-se-1", name: "NXP SE050" }],
                removed: [{ key: "hw:hw-tpm-1", name: "Infineon SLB9665" }],
                changed: [
                  { key: "hw:hw-hsm-1", "bom-ref": "hw:hw-hsm-1", changes: [
                    { path: "firmware.details.version", before: "4.21.2", after: "4.22.0" },
                    { path: "evidence.last_seen", before: "2026-10-10T09:30:00+00:00",
                      after: "2026-10-17T09:30:00+00:00" },
                  ] },
                ],
                unchanged: 0,
              },
              metadata_changes: [],
              summary: { baseline_components: 2, target_components: 2,
                         added: 1, removed: 1, changed: 1, unchanged: 0 },
            },
          };
        }
        return {
          target: snapshotRow, baseline: olderSnapshotRow, note: "",
          diff: {
            key_by: "asset_id", identical: false,
            excluded_paths: ["evidence.last_seen", "as_of"],
            components: {
              key_by: "asset_id",
              added: [{ key: "hw:hw-se-1", name: "NXP SE050" }],
              removed: [{ key: "hw:hw-tpm-1", name: "Infineon SLB9665" }],
              changed: [
                { key: "hw:hw-hsm-1", "bom-ref": "hw:hw-hsm-1", changes: [
                  { path: "firmware.details.version", before: "4.21.2", after: "4.22.0" },
                ] },
              ],
              unchanged: 0,
            },
            metadata_changes: [],
            summary: { baseline_components: 2, target_components: 2,
                       added: 1, removed: 1, changed: 1, unchanged: 0 },
          },
        };
      },
    });
    renderPage();

    await waitFor(() => expect(screen.getByText("Unified Estate HBOM")).toBeTruthy());

    // diff the newest pin against the previous (older) one
    fireEvent.click(await screen.findByText("Diff vs Prev"));
    await waitFor(() => expect(screen.getByText("PIN COMPARISON")).toBeTruthy());
    expect(screen.getByText("+1 added")).toBeTruthy();
    expect(screen.getByText("−1 removed")).toBeTruthy();
    expect(screen.getByText("1 changed")).toBeTruthy();
    // field-level drift on the surviving device
    expect(await screen.findByText("hw:hw-hsm-1")).toBeTruthy();
    expect(screen.getByText(/firmware\.details\.version/)).toBeTruthy();
    expect(screen.getByText("4.22.0")).toBeTruthy();
    // estate mode names what it excluded as observation churn
    expect(screen.getByText(/Excluded as observation churn/i)).toBeTruthy();
    // the diff fetch carried the default estate keying
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining("/api/v1/hbom/snapshots/snap-hbom-1/diff?against=snap-hbom-0&key_by=asset_id"),
      expect.anything());

    // switching to exact mode refetches with key_by=bom_ref and shows
    // the observation churn path estate mode excludes
    fireEvent.click(screen.getByText("exact"));
    await waitFor(() => expect(screen.getByText(/evidence\.last_seen/)).toBeTruthy());
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining("key_by=bom_ref"),
      expect.anything());
    expect(screen.getByText(/Exact mode: every field the documents carry/i)).toBeTruthy();
  });

  it("stays honest when the backend is unreachable", async () => {
    offlineFetch();
    renderPage();

    await waitFor(() => expect(screen.getByText(/Estate document unavailable/i)).toBeTruthy());
    expect(screen.getByText(/Snapshot list unavailable/i)).toBeTruthy();
    expect(screen.queryByText("hw-hsm-1")).toBeNull();
  });
});
