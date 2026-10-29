/* Compliance page truth (product vision §4.3, P0 trust gap): an empty or
 * failed controls response must never become a green 100%; retention is
 * only shown when configured; "unknown" is distinct from FAIL; framework
 * buttons filter honestly and say when a framework is unmapped. */
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { mockFetch, offlineFetch } from "../test/setup";
import Compliance from "./Compliance";

afterEach(() => {
  localStorage.clear();
});

const renderPage = () =>
  render(
    <MemoryRouter>
      <Compliance />
    </MemoryRouter>,
  );

const controls = [
  { control: "access.session_config", status: "pass", evidence: {}, checked_at: "2026-10-13T00:00:00Z" },
  { control: "audit.chain_integrity", status: "fail", evidence: {}, checked_at: "2026-10-13T00:00:00Z" },
  { control: "deploy.schema_in_sync", status: "unknown", evidence: {}, checked_at: "2026-10-13T00:00:00Z" },
];

describe("Compliance — no false green", () => {
  it("shows 100% only from real passing controls, with the denominator", async () => {
    mockFetch({
      "/api/v1/compliance/evidence": { controls: [
        { control: "access.session_config", status: "pass", evidence: {}, checked_at: null },
        { control: "audit.chain_integrity", status: "pass", evidence: {}, checked_at: null },
      ] },
      "/api/v1/compliance/retention": { policy: { audit_log_years: 3 } },
    });
    renderPage();
    await waitFor(() => expect(screen.getAllByText("100%")).toHaveLength(2));
    expect(screen.getByText("2 passing of 2 controls")).toBeTruthy();
    expect(screen.getByText("3 Years")).toBeTruthy();
  });

  it("an empty controls response is NOT a 100% score", async () => {
    mockFetch({
      "/api/v1/compliance/evidence": { controls: [] },
      "/api/v1/compliance/retention": { policy: { audit_log_years: 3 } },
    });
    renderPage();
    await waitFor(() => expect(screen.getByText("Not evaluated — no controls returned")).toBeTruthy());
    expect(screen.queryByText("100%")).toBeNull();
  });

  it("an unreachable evidence source shows no score and no violation claim", async () => {
    offlineFetch();
    renderPage();
    await waitFor(() => expect(screen.getByText(/Compliance evidence unavailable/i)).toBeTruthy());
    expect(screen.queryByText("100%")).toBeNull();
    expect(screen.getByText("No evaluation — no claim")).toBeTruthy();
  });

  it("counts fails and unknowns separately; unknown is not a violation", async () => {
    mockFetch({
      "/api/v1/compliance/evidence": { controls },
      "/api/v1/compliance/retention": { policy: { audit_log_years: 3 } },
    });
    renderPage();
    await waitFor(() => expect(screen.getAllByText("33%")).toHaveLength(2)); // 1/3 passing
    expect(screen.getByText("1/3 passing · 1 fail · 1 unknown")).toBeTruthy();
    expect(screen.getByText("UNKNOWN")).toBeTruthy(); // distinct badge, not FAIL
  });

  it("retention shows Not configured when the policy is absent, never a default 7", async () => {
    mockFetch({
      "/api/v1/compliance/evidence": { controls },
      "/api/v1/compliance/retention": {},
    });
    renderPage();
    await waitFor(() => expect(screen.getByText("Not configured")).toBeTruthy());
    expect(screen.queryByText("7 Years")).toBeNull();
  });

  it("an unmapped framework says nothing was evaluated instead of showing all rows", async () => {
    mockFetch({
      "/api/v1/compliance/evidence": { controls },
      "/api/v1/compliance/retention": { policy: { audit_log_years: 3 } },
    });
    renderPage();
    await waitFor(() => expect(screen.getByText("access.session_config")).toBeTruthy());

    fireEvent.click(screen.getByRole("button", { name: /PCI-DSS/ }));
    expect(screen.queryByText("access.session_config")).toBeNull();
    expect(screen.getByText(/the evidence engine has no control mapping for PCI-DSS/)).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: /SOC 2/ }));
    await waitFor(() => expect(screen.getByText("access.session_config")).toBeTruthy());
  });
});

/* ── Requirements register (§4.3): requirement → evidence / gap / expiry /
 * reviewer sign-off, evaluated against the latest PINNED evidence pack. ── */

const registerPack = {
  pack: {
    pack_id: "p1",
    pack_sha256: "a".repeat(64),
    generated_at: "2026-10-13T00:00:00Z",
    integrity: "OK",
  },
  requirements: [
    {
      requirement: "SOC2-CC6.1",
      title: "Logical access controls over systems and data",
      standing: "evidenced",
      closed: true,
      freshness_days: 90,
      expiry: { state: "fresh", age_days: 3 },
      mapped_controls: ["access.session_config"],
      evidence_controls: [{ control: "access.session_config", status: "pass" }],
      gap: "Collection-time snapshot of platform auth configuration only.",
      sign_off: { required: true, state: "signed", records: [{ signed_by: "ciso@example.com", jws_valid: true }] },
    },
    {
      requirement: "SOC2-CC7.2",
      title: "Audit trail integrity",
      standing: "expired",
      closed: false,
      freshness_days: 30,
      expiry: { state: "expired", age_days: 44 },
      mapped_controls: ["audit.chain_integrity"],
      evidence_controls: [{ control: "audit.chain_integrity", status: "pass" }],
      gap: "Local audit chain only.",
      sign_off: { required: true, state: "signed", records: [{ signed_by: "ciso@example.com", jws_valid: true }] },
    },
    {
      requirement: "SOC2-CC8.1",
      title: "Change management",
      standing: "awaiting_sign_off",
      closed: false,
      freshness_days: 30,
      expiry: { state: "fresh", age_days: 2 },
      mapped_controls: ["deploy.schema_in_sync"],
      evidence_controls: [{ control: "deploy.schema_in_sync", status: "pass" }],
      gap: "Schema drift only.",
      sign_off_scope: "SOC2-CC8.1",
      sign_off: { required: true, state: "unsigned", records: [] },
    },
    {
      requirement: "PCI-DSS-4.2.1",
      title: "Network segmentation between the CDE and other networks",
      standing: "unevaluated",
      closed: false,
      freshness_days: null,
      expiry: { state: "not_applicable" },
      mapped_controls: [],
      evidence_controls: [],
      gap: "No control in the platform evidence engine maps to cardholder-data segmentation.",
      sign_off_scope: "PCI-DSS-4.2.1",
      sign_off: { required: true, state: "unsigned", records: [] },
    },
  ],
  summary: { closed: 1, denominator: 4, signed: 2 },
};

const noPackRegister = {
  pack: null,
  requirements: registerPack.requirements.map((r) => ({
    ...r, standing: "no_evidence", closed: false,
    expiry: { state: "no_evidence", age_days: null },
  })),
  summary: { closed: 0, denominator: 4, signed: 0 },
  note: "no evidence pack has been pinned — requirements are not evaluated.",
};

describe("Compliance — requirements register", () => {
  it("maps every requirement to evidence, gap, expiry and sign-off with an explicit denominator", async () => {
    mockFetch({
      "/api/v1/compliance/evidence": { controls },
      "/api/v1/compliance/retention": { policy: { audit_log_years: 3 } },
      "/api/v1/compliance/requirements": registerPack,
    });
    renderPage();
    await waitFor(() => expect(screen.getByText("SOC2-CC6.1")).toBeTruthy());
    // the four dimensions travel with each row
    expect(screen.getByText("Collection-time snapshot of platform auth configuration only.")).toBeTruthy();
    expect(screen.getByText(/EXPIRED — older than 30d window/)).toBeTruthy();
    expect(screen.getAllByText(/✓ signed by ciso@example.com/).length).toBe(2);
    // unmapped requirement stays visible and unevaluated — never hidden
    expect(screen.getByText("PCI-DSS-4.2.1")).toBeTruthy();
    expect(screen.getByText("No automated evidence mapped")).toBeTruthy();
    expect(screen.getByText("UNEVALUATED")).toBeTruthy();
    // explicit denominator — not a percentage of a hidden subset
    expect(screen.getByText("1 of 4 requirements closed")).toBeTruthy();
    // unsigned requirement offers a real sign-off action
    expect(screen.getAllByRole("button", { name: "Sign off" }).length).toBe(2);
  });

  it("shows not-evaluated when no pack is pinned, and pinning establishes the evidence", async () => {
    let pinned = false;
    const fetchSpy = mockFetch({
      "/api/v1/compliance/evidence": { controls: [] },
      "/api/v1/compliance/retention": { policy: { audit_log_years: 3 } },
      "/api/v1/compliance/requirements": () => (pinned ? registerPack : noPackRegister),
      "/api/v1/compliance/evidence/packs": () => {
        pinned = true;
        return { pack_id: "p1", pack_sha256: "a".repeat(64), created: true, controls: 6 };
      },
    });
    renderPage();
    await waitFor(() => expect(screen.getByText(/No evidence pack pinned — requirements are not evaluated/)).toBeTruthy());
    // the register stays visible, honestly: every requirement says NO EVIDENCE
    expect(screen.getByText("SOC2-CC6.1")).toBeTruthy();
    expect(screen.getAllByText("NO EVIDENCE").length).toBe(4);
    expect(screen.getByText("0 of 4 requirements closed")).toBeTruthy();
    expect(screen.queryByText(/EXPIRED/)).toBeNull(); // nothing evaluated, nothing claimed

    fireEvent.click(screen.getByRole("button", { name: "Pin Current Evidence" }));
    const post = fetchSpy.mock.calls.find(([p, init]) => String(p) === "/api/v1/compliance/evidence/packs" && init?.method === "POST");
    expect(post).toBeTruthy();
    await waitFor(() => expect(screen.getByText("1 of 4 requirements closed")).toBeTruthy());
    // after pinning, evidence (and its age) is actually evaluated
    expect(screen.getByText(/EXPIRED — older than 30d window/)).toBeTruthy();
  });

  it("signs a requirement off over the pinned pack and records the reviewer", async () => {
    let signed = false;
    mockFetch({
      "/api/v1/compliance/evidence": { controls },
      "/api/v1/compliance/retention": { policy: { audit_log_years: 3 } },
      "/api/v1/compliance/requirements": () =>
        signed
          ? {
              ...registerPack,
              requirements: registerPack.requirements.map((r) =>
                r.requirement === "SOC2-CC8.1"
                  ? { ...r, standing: "evidenced", closed: true, sign_off: { required: true, state: "signed", records: [{ signed_by: "bob@example.com", jws_valid: true }] } }
                  : r,
              ),
              summary: { closed: 2, denominator: 4, signed: 3 },
            }
          : registerPack,
      "/api/v1/compliance/attestations": (_url: string, init?: RequestInit) => {
        signed = true;
        return { jws: "h.p.s", snapshot: {}, persisted: true, attestation_id: "a1" };
      },
    });
    renderPage();
    await waitFor(() => expect(screen.getByText("SOC2-CC8.1")).toBeTruthy());
    // sign-off needs a reviewer identity — the button stays disabled without one
    const signButtons = screen.getAllByRole("button", { name: "Sign off" });
    expect(signButtons.every((b) => (b as HTMLButtonElement).disabled)).toBe(true);
    fireEvent.change(screen.getByLabelText("Reviewer name"), { target: { value: "bob@example.com" } });
    fireEvent.click(signButtons[0]); // first unsigned row: SOC2-CC8.1
    await waitFor(() => expect(screen.getByText(/✓ signed by bob@example.com/)).toBeTruthy());
    expect(screen.getByText("2 of 4 requirements closed")).toBeTruthy();
  });
});
