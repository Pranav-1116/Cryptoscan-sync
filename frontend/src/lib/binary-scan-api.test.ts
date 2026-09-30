import { describe, expect, it } from "vitest";
import { mockFetch } from "../test/setup";
import {
  apiBinaryScanCompare, apiBinaryScanCoverage, apiBinaryScanDetail,
  apiBinaryScanFindings, apiBinaryScanObservations, apiBinaryScans, setActiveTenantId,
} from "./api";

describe("binary scan read-model API", () => {
  it("sends tenant scope and query filters for history", async () => {
    setActiveTenantId("tenant-a");
    const fetchSpy = mockFetch({ "/api/v1/devsecops/binary/scans": { records: [], total: 0 } });
    const answer = await apiBinaryScans({ q: "firmware", limit: 10 });
    expect(answer.source).toBe("live");
    const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(url).toContain("/api/v1/devsecops/binary/scans?");
    expect(url).toContain("q=firmware");
    expect((init.headers as Record<string, string>)["X-Tenant-ID"]).toBe("tenant-a");
  });

  it("encodes scan ids for detail retrieval and preserves partial observations", async () => {
    const id = "scan/a?b";
    mockFetch({ "/api/v1/devsecops/binary/scans/scan%2Fa%3Fb": {
      record: { id, observations_truncated: true },
      observations: [{ path: "lib.so", evidence_state: "partial" }],
    } });
    const answer = await apiBinaryScanDetail(id);
    expect(answer.ok).toBe(true);
    expect(answer.data?.record.observations_truncated).toBe(true);
    expect(answer.data?.observations[0].evidence_state).toBe("partial");
  });

  it("supports observation, finding, coverage, and comparison API views", async () => {
    const fetchSpy = mockFetch({
      "/api/v1/devsecops/binary/scans/scan-a/observations": { total: 1, observations: [{ path: "lib.so" }] },
      "/api/v1/devsecops/binary/scans/scan-a/findings": { total: 1, findings: [{ code: "BIN-X" }] },
      "/api/v1/devsecops/binary/scans/scan-a/coverage": { evidence_states: { observed: 1 } },
      "/api/v1/devsecops/binary/scans/compare": { counts: { added: 1, removed: 0, changed: 0 } },
    });
    expect((await apiBinaryScanObservations("scan-a", { evidence_state: "partial", crypto_only: true })).data?.total).toBe(1);
    expect((await apiBinaryScanFindings("scan-a", { severity: "HIGH" })).data?.findings[0].code).toBe("BIN-X");
    expect((await apiBinaryScanCoverage("scan-a")).data?.evidence_states.observed).toBe(1);
    expect((await apiBinaryScanCompare("scan-a", "scan-b")).data?.counts.added).toBe(1);
    const calls = fetchSpy.mock.calls.map((call) => String(call[0]));
    expect(calls.some((url) => url.includes("evidence_state=partial") && url.includes("crypto_only=true"))).toBe(true);
    expect(calls.some((url) => url.includes("severity=HIGH"))).toBe(true);
  });
});
