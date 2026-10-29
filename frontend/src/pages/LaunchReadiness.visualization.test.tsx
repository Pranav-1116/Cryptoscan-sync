/* Launch readiness — the drawing contract.
 *
 * These pin what the screen claims visually: a duty's state is its server issue
 * codes, the SLA rail is the payload's own boolean plus its reason, and a
 * payload without a duty array draws an absence instead of nine green cells.
 */
import React from "react";
import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { mockFetch } from "../test/setup";
import LaunchReadiness from "./LaunchReadiness";

const P = "/api/v1/assurance/launch/";
const draw = () => render(<MemoryRouter><LaunchReadiness /></MemoryRouter>);
const DUTIES = [
  "VULNERABILITY_RESPONSE", "INCIDENT_RESPONSE", "BACKUP_RESTORE", "CERTIFICATE_ROTATION",
  "CREDENTIAL_ROTATION", "SUPPORT_ESCALATION", "RELEASE_APPROVAL", "DATA_RETENTION", "CUSTOMER_OFFBOARDING",
];
const operations = (gapped: string | null) => ({
  duties: DUTIES.map((duty) => ({ duty, issues: duty === gapped ? ["UNASSIGNED"] : [], assignment: duty === gapped ? null : { id: `as-${duty}` }, exercise: duty === gapped ? null : { id: `ex-${duty}` } })),
  all_owner_reviewed_records_current: gapped === null,
  sla_authorized: false,
  reason: "Contracts/SLOs require demonstrated site capability",
});
afterEach(() => localStorage.clear());

describe("Launch readiness visualization", () => {
  it("draws every returned duty with its own state and its coded gap", async () => {
    mockFetch({ [P + "operations"]: operations("BACKUP_RESTORE") });
    draw();
    expect(await screen.findByText("BACKUP RESTORE")).toBeInTheDocument();
    // one gapped duty out of nine, and the gap is named rather than counted silently
    expect(screen.getByText("8 clean · 1 with gaps")).toBeInTheDocument();
    expect(screen.getByText(/no assignment/)).toBeInTheDocument();
    expect(screen.getByText("1 gap")).toBeInTheDocument();
    expect(screen.getAllByText("CLEAN")).toHaveLength(8);
    // the register composition is drawn from the same counts, not from a score
    expect(screen.getByText("clean duty")).toBeInTheDocument();
    expect(screen.getByText("duty with gaps")).toBeInTheDocument();
  });

  it("states that no SLA is authorised and repeats the payload's own reason", async () => {
    mockFetch({ [P + "operations"]: operations(null) });
    draw();
    expect(await screen.findByText("NOT AUTHORIZED")).toBeInTheDocument();
    expect(screen.getByText("Contracts/SLOs require demonstrated site capability")).toBeInTheDocument();
    expect(screen.getByText("not measured")).toBeInTheDocument(); // the hatched SLA rail, not a 0
    expect(screen.getByText("CURRENT")).toBeInTheDocument();
  });

  it("draws an absence when the payload carries no duty register at all", async () => {
    mockFetch({ [P + "operations"]: { sla_authorized: false } });
    draw();
    expect(await screen.findByText(/No duty register in this read/)).toBeInTheDocument();
    expect(screen.queryByText("CLEAN")).not.toBeInTheDocument();
    expect(screen.getByText("NOT OBSERVED")).toBeInTheDocument();
  });

  it("keeps the duty board empty after a failed refresh instead of grading an old read", async () => {
    mockFetch({ [P + "operations"]: operations("BACKUP_RESTORE") });
    draw();
    await screen.findByText("BACKUP RESTORE");
    mockFetch({}, 503);
    fireEvent.click(screen.getByText("Refresh operating records"));
    expect(await screen.findByRole("alert")).toHaveTextContent("503");
    expect(screen.queryByText("BACKUP RESTORE")).not.toBeInTheDocument();
    expect(screen.queryByText("CLEAN")).not.toBeInTheDocument();
  });

  it("draws a returned record as its own scalars above the retained document", async () => {
    mockFetch({ [P + "operations"]: operations(null), [P + "pilots/p-1/status"]: { state: "PROPOSED", evidence_loop_ready: false } });
    draw();
    await screen.findByText("BACKUP RESTORE");
    fireEvent.change(screen.getByLabelText("Exact record ID"), { target: { value: "p-1" } });
    fireEvent.click(screen.getByText("Read bounded pilot status"));
    expect(await screen.findByText("PROPOSED")).toBeInTheDocument();
    expect(screen.getByText("evidence loop ready")).toBeInTheDocument();
    expect(screen.getByText("Retained record")).toBeInTheDocument();
  });
});
