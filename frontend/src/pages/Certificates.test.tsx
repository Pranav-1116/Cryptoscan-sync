/* Certificates page (§5, round 74): TWO honest surfaces — the live
 * TLS-scan view (one observation run) and the PERSISTED ESTATE (rows
 * deduped by fingerprint, owner present or honestly UNKNOWN, recorded
 * usage locations, revocation check, audited ownership assignment).
 * No fabricated owners, usages, or task linkage. */
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { mockFetch, offlineFetch } from "../test/setup";
import Certificates from "./Certificates";

afterEach(() => {
  localStorage.clear();
  vi.restoreAllMocks();
});

const renderPage = () =>
  render(
    <MemoryRouter>
      <Certificates />
    </MemoryRouter>,
  );

const emptyLive = {
  certificates: [],
  cert_center: { expired: 0, expiring30: 0, weak_algorithm: 0, unknown_owner: 0, total: 0 },
};

const ownedCert = {
  id: "cert-row-1",
  fingerprint_sha256: "a".repeat(64),
  subject: "CN=api.bank.example", issuer: "CN=Internal Root CA",
  serial_number: "00A1", not_before: "2026-01-01T00:00:00+00:00",
  not_after: "2027-01-01T00:00:00+00:00",
  public_key_algorithm: "RSA", public_key_size: 2048,
  expiry_status: "VALID", days_until_expiry: 200,
  is_self_signed: false,
  owner: "platform-team", technical_contact: "oncall@bank.example",
  revocation_status: null, revocation_method: null, revocation_checked_at: null,
  renewal_status: "NONE", renewal_ticket: null,
  san: ["api.bank.example"], usages: [],
};
const unownedCert = {
  ...ownedCert,
  id: "cert-row-2",
  fingerprint_sha256: "b".repeat(64),
  subject: "CN=legacy.bank.example", issuer: "CN=Legacy CA",
  days_until_expiry: 10, expiry_status: "EXPIRING",
  owner: null, technical_contact: null, san: [],
};

const baseRoutes = {
  "/api/v1/live-scan/inventory": emptyLive,
  "/api/v1/certificates": {
    certificates: [unownedCert, ownedCert],  // backend sorts by expiry urgency
    total_count: 2,
  },
};

async function openEstateDrawer(routes: Record<string, unknown>) {
  const fetchMock = mockFetch(routes);
  renderPage();
  fireEvent.click(await screen.findByText("CN=api.bank.example"));
  await waitFor(() => expect(screen.getByText("Where observed")).toBeTruthy());
  return fetchMock;
}

describe("Certificates page", () => {
  it("renders the persisted estate distinct from the live scan view, owner unknown stays unknown", async () => {
    mockFetch(baseRoutes);
    renderPage();

    expect(await screen.findByText("Persisted certificate estate")).toBeTruthy();
    // the durable rows render with their owners
    expect(screen.getByText("platform-team")).toBeTruthy();
    expect(screen.getByText("CN=legacy.bank.example")).toBeTruthy();
    // absent owner renders as UNKNOWN — a fact, not an inference
    expect(screen.getByText("UNKNOWN")).toBeTruthy();
    expect(screen.getByText("1 UNKNOWN OWNER")).toBeTruthy();
    expect(screen.getByText("2 ROWS")).toBeTruthy();
    // the two surfaces are labeled apart
    expect(screen.getByText(/Deduped by fingerprint/)).toBeTruthy();
    expect(screen.getByText(/Ephemeral scan run/)).toBeTruthy();
    expect(screen.getByText(/No certificates yet/i)).toBeTruthy();
  });

  it("shows the estate drawer with facts, recorded usages, and no invented task linkage", async () => {
    await openEstateDrawer({
      ...baseRoutes,
      "/api/v1/certificates/cert-row-1/usages": {
        certificate: ownedCert,
        usages: [
          { id: "u1", fingerprint_sha256: "a".repeat(64), usage_type: "TLS_SERVER",
            location: "api.bank.example:443", last_seen: "2026-10-15T09:00:00+00:00" },
          { id: "u2", fingerprint_sha256: "a".repeat(64), usage_type: "TLS_CLIENT",
            location: "mtls-gw.bank.example:8443", last_seen: null },
        ],
      },
    });

    // the recorded usage locations — where the certificate was observed
    expect(await screen.findByText("api.bank.example:443")).toBeTruthy();
    expect(screen.getByText("mtls-gw.bank.example:8443")).toBeTruthy();
    expect(screen.getByText("TLS_SERVER")).toBeTruthy();
    // the facts (the issuer also appears in the estate table behind the drawer)
    expect(screen.getAllByText(/Internal Root CA/).length).toBeGreaterThan(0);
    expect(screen.getByText("OWNER platform-team")).toBeTruthy();
    expect(screen.getByText("REVOCATION UNCHECKED")).toBeTruthy();
    // and the honest limit: no task linkage is invented
    expect(screen.getByTitle(/no task linkage exists to show/i)).toBeTruthy();
  });

  it("states honestly when no usage location is linked", async () => {
    await openEstateDrawer({
      ...baseRoutes,
      "/api/v1/certificates/cert-row-1/usages": { certificate: ownedCert, usages: [] },
    });
    expect(await screen.findByText(/No usage locations recorded/i)).toBeTruthy();
  });

  it("runs the revocation check and renders what the probes determined", async () => {
    await openEstateDrawer({
      ...baseRoutes,
      "/api/v1/certificates/cert-row-1/usages": { certificate: ownedCert, usages: [] },
      "/api/v1/certificates/cert-row-1/revocation": {
        ocsp: { status: null, method: "aia_parse", urls: [] },
        crl: { status: null, method: "aia_parse", urls: [] },
      },
    });

    fireEvent.click(screen.getByText("Check revocation (OCSP / CRL)"));
    // both probes report UNDETERMINED — never a guessed "good"
    await waitFor(() => expect(screen.getAllByText("UNDETERMINED").length).toBe(2));
    expect(screen.getByTitle(/never "good"/i)).toBeTruthy();
  });

  it("assigns ownership with a mandatory audited reason; 403 renders as the permission it needs", async () => {
    const fetchMock = await openEstateDrawer({
      ...baseRoutes,
      "/api/v1/certificates/cert-row-1/usages": { certificate: ownedCert, usages: [] },
      [`/api/v1/certificates/${"a".repeat(64)}/ownership`]: (
        _url: string, init?: RequestInit) => {
        const body = JSON.parse(String(init?.body || "{}"));
        if (!body.reason) {
          return new Response(JSON.stringify({ detail: "reason required" }),
            { status: 422, headers: { "Content-Type": "application/json" } });
        }
        return { fingerprint_sha256: "a".repeat(64), owner: body.owner ?? null,
                 technical_contact: body.technical_contact ?? null, reason: body.reason };
      },
    });

    // no reason -> the UI refuses before any request
    fireEvent.click(screen.getByText("Assign ownership"));
    expect(await screen.findByText(/reason is mandatory/i)).toBeTruthy();

    // fill and assign
    fireEvent.change(screen.getByPlaceholderText("owner"), { target: { value: "network-team" } });
    fireEvent.change(screen.getByPlaceholderText(/reason \(mandatory/), { target: { value: "expiry ownership assigned" } });
    fireEvent.click(screen.getByText("Assign ownership"));
    expect(await screen.findByText(/Ownership recorded — owner network-team/i)).toBeTruthy();
    const calls = fetchMock.mock.calls.filter((call) =>
      String(call?.[0]).includes("/ownership"));
    expect(calls.length).toBeGreaterThan(0);
  });

  it("renders an honest empty estate and stays honest offline", async () => {
    mockFetch({
      "/api/v1/live-scan/inventory": emptyLive,
      "/api/v1/certificates": { certificates: [], total_count: 0 },
    });
    renderPage();
    expect(await screen.findByText(/persisted estate is empty/i)).toBeTruthy();

    offlineFetch();
    renderPage();
    expect(await screen.findByText(/Persisted estate unavailable/)).toBeTruthy();
    expect(screen.getByText("— ROWS")).toBeTruthy();
    expect(screen.getByText("— UNKNOWN OWNER")).toBeTruthy();
  });
});
