import React from "react";
import { fireEvent, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import PrivateScope from "./PrivateScope";
import { setActiveTenantId } from "../lib/api";
import { renderWithProviders } from "../test/render";
import { mockFetch } from "../test/setup";
import EstateSchedulePanel from "./EstateSchedulePanel";

const path = "/api/v1/estate/evidence/schedules";
const saved = {
  id: "11111111-1111-1111-1111-111111111111", name: "repo-hourly", tenant_id: "a", enabled: true,
  planes: ["STATIC"], next_run_at: "2026-10-29T00:00:00Z", consecutive_failures: 0,
  cadence: { every: "60m", interval_minutes: 60 },
  last_run: { at: null, run_id: null, verdict: null, coverage_state: null },
};
const view = () => renderWithProviders(<PrivateScope><EstateSchedulePanel /></PrivateScope>, { route: "/live-monitor" });

describe("retained-evidence schedule workflow", () => {
  it("submits one explicit stored plane with tenant authority, then reads the receipt", async () => {
    localStorage.setItem("zelinx_roles", JSON.stringify(["superadmin"]));
    setActiveTenantId("a");
    let created = false;
    const fetch = mockFetch({ [path]: (_url: string, init?: RequestInit) => {
      if (init?.method === "POST") {
        expect(new Headers(init.headers).get("X-Tenant-ID")).toBe("a");
        expect(JSON.parse(String(init.body))).toEqual({ name: "repo-hourly", every: "1h", planes: ["STATIC"],
          enabled: true, scope: "local", estate: "default" });
        created = true;
        return saved;
      }
      return { model: "cryptoscan.estate-schedules/1", schedules: created ? [saved] : [], note: "stored" };
    } });
    view();
    expect(await screen.findByText("No schedules in this estate. Nothing is reprojected.")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Schedule name"), { target: { value: "repo-hourly" } });
    fireEvent.change(screen.getByLabelText("Schedule interval"), { target: { value: "1h" } });
    fireEvent.click(screen.getByRole("button", { name: "Enable projection cadence" }));
    expect(await screen.findByText(/Projection schedule repo-hourly saved/)).toHaveTextContent("No new collection was authorized");
    expect(await screen.findByText("NOT_RUN")).toBeInTheDocument();
    expect(screen.getByText("UNKNOWN")).toBeInTheDocument();
    expect(fetch.mock.calls.filter(([, init]) => init?.method === "POST")).toHaveLength(1);
  });

  it("does not offer a write to readonly users or invent an empty list on failure", async () => {
    localStorage.setItem("zelinx_roles", JSON.stringify(["readonly"]));
    mockFetch({ [path]: () => new Response(JSON.stringify({ detail: "denied" }), { status: 403 }) });
    view();
    expect(await screen.findByRole("alert")).toHaveTextContent("Schedule list unavailable");
    expect(screen.queryByRole("button", { name: "Enable projection cadence" })).toBeNull();
    expect(screen.queryByText("No schedules in this estate. Nothing is reprojected.")).toBeNull();
  });

  it("leaves a refused write unconfirmed instead of reporting a saved cadence", async () => {
    localStorage.setItem("zelinx_roles", JSON.stringify(["superadmin"]));
    mockFetch({ [path]: (_url: string, init?: RequestInit) => init?.method === "POST"
      ? new Response(JSON.stringify({ detail: "current session required" }), { status: 403 })
      : { model: "cryptoscan.estate-schedules/1", schedules: [], note: "stored" },
    });
    view();
    await screen.findByText("No schedules in this estate. Nothing is reprojected.");
    fireEvent.change(screen.getByLabelText("Schedule name"), { target: { value: "refused" } });
    fireEvent.click(screen.getByRole("button", { name: "Enable projection cadence" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Schedule outcome unconfirmed");
    expect(screen.queryByText(/Projection schedule refused saved/)).toBeNull();
  });
});
