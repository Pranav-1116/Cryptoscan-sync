/* System-health truth (product vision §5, P0 trust bug): the helpers must
 * never turn API liveness into green engines, synthetic latencies, zero
 * errors or 100% availability. Measured probes only; everything else is
 * reported "Not measured" / "On demand". */
import { afterEach, describe, expect, it } from "vitest";
import { setToken } from "../lib/api";
import { mockFetch, offlineFetch } from "../test/setup";
import { apiScannerEnginesHealth, apiSystemHealthStatus } from "./api";

afterEach(() => {
  localStorage.clear();
});

describe("apiSystemHealthStatus — no fabricated green", () => {
  it("reports only the Core API as Operational from /healthz alone", async () => {
    mockFetch({
      "/healthz": { status: "ok" },
      "/healthz/dependencies": {
        status: "ok", down: [],
        checks: [
          { name: "database", status: "ok", detail: "postgresql" },
          { name: "redis", status: "skipped", detail: "not configured" },
          { name: "neo4j", status: "skipped", detail: "not configured" },
        ],
      },
    });
    const rows = await apiSystemHealthStatus();
    const byName = new Map(rows.map((r) => [r.name, r]));

    expect(byName.get("Core API")?.status).toBe("Operational");
    expect(byName.get("Core API")?.latencyMs).toBeGreaterThanOrEqual(0);
    // no SLO window -> availability must NOT claim 100%
    expect(byName.get("Core API")?.details).toContain("not measured");

    // measured dependency probes are reported as measured
    expect(byName.get("PostgreSQL (evidence store)")?.status).toBe("Operational");
    // skipped optional dependencies are Not measured, not green
    expect(byName.get("Redis (events / queue transport)")?.status).toBe("Not measured");
    expect(byName.get("Neo4j (graph)")?.status).toBe("Not measured");

    // engines with no independent probe are NEVER green
    for (const name of [
      "Deterministic Policy Engine", "Drift Engine", "WORM Evidence Store",
      "Digital Twin Engine", "Queue & Worker Pool",
    ]) {
      const row = byName.get(name);
      expect(row?.status, name).toBe("Not measured");
      expect(row?.latencyMs, name).toBeNull();
    }
  });

  it("marks a down dependency Degraded, not Operational", async () => {
    mockFetch({
      "/healthz": { status: "ok" },
      "/healthz/dependencies": {
        status: "degraded", down: ["database"],
        checks: [
          { name: "database", status: "down", detail: "connection refused" },
          { name: "redis", status: "ok", detail: "pong" },
        ],
      },
    });
    const rows = await apiSystemHealthStatus();
    const byName = new Map(rows.map((r) => [r.name, r]));
    expect(byName.get("PostgreSQL (evidence store)")?.status).toBe("Degraded");
    expect(byName.get("Redis (events / queue transport)")?.status).toBe("Operational");
  });

  it("uses the measured SLO window when present", async () => {
    setToken("tok");
    mockFetch({
      "/healthz": { status: "ok" },
      "/healthz/dependencies": { status: "ok", down: [], checks: [] },
      "/api/v1/ops/slo": {
        latency: { p99_ms: 123.4 },
        availability: { achieved: 0.9972 },
      },
    });
    const rows = await apiSystemHealthStatus();
    const api = rows.find((r) => r.name === "Core API");
    expect(api?.details).toContain("99.7%");
    expect(api?.details).toContain("p99 123 ms");
  });

  it("reports Offline when the API is unreachable, with null latency", async () => {
    offlineFetch();
    const rows = await apiSystemHealthStatus();
    const api = rows.find((r) => r.name === "Core API");
    expect(api?.status).toBe("Offline");
    expect(api?.latencyMs).toBeNull();
  });
});

describe("apiScannerEnginesHealth — scanners are on-demand collectors", () => {
  it("never claims Healthy/Active from API liveness", async () => {
    setToken("tok");
    mockFetch({
      "/healthz": { status: "ok" },
      "/api/v1/assets": { total_count: 42 },
    });
    const engines = await apiScannerEnginesHealth();
    expect(engines.length).toBeGreaterThan(0);
    for (const e of engines) {
      expect(e.status, e.id).toBe("On demand");
      expect(e.lastObservation, e.id).toContain("No continuous probe");
      expect(e.errors, e.id).toBe(0); // no counter exists; nothing claimed
      expect(e.avgLatencyMs, e.id).toBe(0);
    }
    // No engine claims a discovery count of its own: the platform exposes none,
    // and the estate total belongs to the estate, not to one scanner.
    expect(engines.every((e) => e.assetsDiscovered === null)).toBe(true);
    // The estate total is the one measured number, and every row carries it.
    expect(engines.map((e) => e.estateAssets)).toEqual([42, 42, 42, 42, 42]);
  });

  it("reports Offline for every engine when the API is unreachable", async () => {
    offlineFetch();
    const engines = await apiScannerEnginesHealth();
    expect(engines.every((e) => e.status === "Offline")).toBe(true);
  });
});
