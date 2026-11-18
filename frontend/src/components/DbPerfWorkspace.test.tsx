/* Database Performance (docs/performance/03_UI_SPEC.md §4): the nine
   areas with un-collected measurements named as gaps; adapters honest
   (capability ≠ use); the collection contract is query fingerprints and
   normalized statistics — SQL statements containing customer data are
   never collected. Unknowns render "—", never zeros. */

import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import DbPerfWorkspace from "./DbPerfWorkspace";
import type { PerformanceDbWorkspace } from "../lib/api";

const summary = {
  sample_count: 8, value_count: 6, unknown_count: 2,
  coverage: "partial — 6/8 delivered",
  average: 42, minimum: 30, maximum: 60, p50: 40, p95: 58, p99: 60,
};

const data: PerformanceDbWorkspace = {
  areas: {
    connections: { state: "measured", metrics: { "db.connections_active": summary }, missing: ["waiting connections", "connection exhaustion"] },
    queries: { state: "measured", metrics: { "db.query_time_ms": summary }, missing: ["slow query count"] },
    locks: { state: "not_collected", metrics: {}, missing: ["blocking"] },
    cache: { state: "not_collected", metrics: {}, missing: ["buffer utilization"] },
    storage: { state: "measured", metrics: { "db.size_bytes": summary }, missing: ["database growth", "database IOPS"] },
    replication: { state: "not_collected", metrics: {}, missing: ["replication status"] },
    transactions: { state: "not_collected", metrics: {}, missing: ["commit rate", "rollback rate"] },
    backup: { state: "not_collected", metrics: {}, missing: ["backup status", "backup age"] },
    availability: { state: "not_collected", metrics: {}, missing: ["connection failures"] },
  },
  databases: [
    { database: "paydb", platform: "PostgreSQL", connections_active: 42, query_time_ms: 28.4, size_bytes: null, replication_lag_seconds: null, samples: 12, last_observed: "2026-10-16T10:00:00+00:00" },
    { database: "ledgerdb", platform: "not recorded", connections_active: null, query_time_ms: null, size_bytes: null, replication_lag_seconds: null, samples: 3, last_observed: null },
  ],
  adapters: [
    { platform: "PostgreSQL", adapter: "postgres_exporter", state: "adapter available" },
    { platform: "MySQL", adapter: null, state: "no dedicated adapter — generic OTLP ingest only" },
    { platform: "Microsoft SQL Server", adapter: null, state: "no dedicated adapter — generic OTLP ingest only" },
    { platform: "Oracle", adapter: null, state: "no dedicated adapter — generic OTLP ingest only" },
  ],
  collectors: [{ collector_id: "db-collector-1", status: "stale", last_report_at: "2026-10-15T10:00:00+00:00", detail: "last report is older than the freshness window" }],
  note: "statistics only — the collection contract is query fingerprints and normalized statistics; query parameters and customer records are never collected, and SQL statements containing customer data are never collected",
};

const renderWs = (over: Partial<PerformanceDbWorkspace> = {}) =>
  render(<DbPerfWorkspace data={{ ...data, ...over }} />);

describe("Database Performance workspace (§4)", () => {
  it("draws the nine areas with un-collected measurements named, never zeroed", () => {
    renderWs();
    for (const label of ["Connections", "Queries", "Locks", "Cache", "Storage",
      "Replication", "Transactions", "Backup", "Availability"]) {
      expect(screen.getAllByText(label).length).toBeGreaterThanOrEqual(1);
    }
    expect(screen.getAllByText(/not collected: slow query count/).length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText(/database growth, database IOPS/).length).toBeGreaterThanOrEqual(1);
    expect(screen.queryByText("0")).not.toBeInTheDocument();
  });

  it("keeps the collection contract pinned", () => {
    renderWs();
    expect(screen.getAllByText(/query fingerprints and normalized statistics/).length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText(/SQL statements containing customer data are never collected/).length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText(/query parameters and customer records are never collected/).length).toBeGreaterThanOrEqual(1);
  });

  it("keeps adapters as capability, not use", () => {
    renderWs();
    fireEvent.click(screen.getByRole("tab", { name: "Adapters & collectors" }));
    expect(screen.getByText("postgres_exporter")).toBeInTheDocument();
    expect(screen.getAllByText(/adapter available/).length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText(/no dedicated adapter — generic OTLP ingest only/).length).toBeGreaterThanOrEqual(3);
    expect(screen.getByText(/capability — it is not a claim of use/)).toBeInTheDocument();
    // collector health reads the real staleness, not a healthy fiction
    expect(screen.getByText("stale")).toBeInTheDocument();
  });

  it("never invents a platform for an unattributed database", () => {
    renderWs();
    fireEvent.click(screen.getByRole("tab", { name: "Databases" }));
    expect(screen.getByText("paydb")).toBeInTheDocument();
    expect(screen.getByText("PostgreSQL")).toBeInTheDocument();
    expect(screen.getByText(/never invents a platform/)).toBeInTheDocument();
    const dashes = screen.getAllByText("—");
    expect(dashes.length).toBeGreaterThan(0);
    expect(screen.queryByText("0")).not.toBeInTheDocument();
  });

  it("keeps an empty read as a collection gap", () => {
    renderWs({ databases: [] });
    fireEvent.click(screen.getByRole("tab", { name: "Databases" }));
    expect(screen.getByTitle(/collection gap, not a healthy estate/)).toBeInTheDocument();
  });
});
